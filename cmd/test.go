package cmd

import (
	"dkms/share"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share/pvss"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

var (
	testCmd = &cobra.Command{
		Use:   "test",
		Short: "test for dkms",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}

	testPvssCmd = &cobra.Command{
		Use:   "pvss [node num] [t]",
		Short: "pvss verification time check",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			nodeNum, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			t, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			// Benchmark test
			suite := edwards25519.NewBlakeSHA256Ed25519()
			//G := suite.Point().Base()
			H := suite.Point().Pick(suite.XOF([]byte("H")))
			n := nodeNum
			threshold := t
			x := make([]kyber.Scalar, n) // trustee private keys
			X := make([]kyber.Point, n)  // trustee public keys
			for i := 0; i < n; i++ {
				x[i] = suite.Scalar().Pick(suite.RandomStream())
				X[i] = suite.Point().Mul(x[i], nil)
			}

			secret := suite.Scalar().Pick(suite.RandomStream())

			logrus.SetFormatter(&logrus.JSONFormatter{
				TimestampFormat: time.StampMicro,
			})
			logrus.Info("end distribution and start decryption1")
			// (1) Share distribution (dealer)
			encShares, pubPoly, err := pvss.EncShares(suite, H, X, secret, threshold)
			if err != nil {
				return err
			}
			sH := make([]kyber.Point, n)
			// (2) Share decryption (trustees)
			for i := 0; i < n; i++ {
				sH[i] = pubPoly.Eval(encShares[i].S.I).V
			}
			logrus.Info("end distribution and start decryption2")
			for i := 0; i < n; i++ {
				_ = pvss.VerifyEncShare(suite, H, X[i], sH[i], encShares[i])
			}
			logrus.Info("end decryption")
			return nil
		},
	}

	testBivssCmd = &cobra.Command{
		Use:   "pvss [node num] [t]",
		Short: "pvss [node num] [t]",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			nodeNum, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			t, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			suite := edwards25519.NewBlakeSHA256Ed25519()
			secret := suite.Scalar().SetInt64(123)
			u := t
			n := nodeNum

			x := make([]kyber.Scalar, n) // trustee private keys
			X := make([]kyber.Point, n)  // trustee public keys
			poly := GetSamplePoly(suite, secret)

			for i := 0; i < n; i++ {
				x[i] = suite.Scalar().Pick(suite.RandomStream())
				X[i] = suite.Point().Mul(x[i], nil)
			}
			serverPoints := make([][]share.BiPoint, n)
			encShares := make([][]kyber.Point,n)

			logrus.SetFormatter(&logrus.JSONFormatter{
				TimestampFormat: time.StampMicro,
			})
			logrus.Info("start distribution")
			for i := 0; i < n; i++ {
				serverPoints[i] = make([]share.BiPoint, u)
				encShares[i] = make([]kyber.Point, u)
				for j := 0; j < u; j++ {
					serverPoints[i][j] = poly.Eval(int64(i+1),int64(j))
					encShares[i][j] = suite.Point().Mul(serverPoints[i][j].V,X[i])
				}
			}
			H := suite.Point().Pick(suite.XOF([]byte("H")))
			commit := poly.Commit(H)
			w := suite.Scalar().SetInt64(int64(300))
			c := suite.Scalar().SetInt64(int64(2))
			logrus.Info("end distribution and start decryption")
			//distribute end
			for i := 0; i < n; i++ {
				for j :=0; j<u;j++{
					r := share.GenerateRScalar(suite, w, c,serverPoints[i][j])
					share.VerifyRScalar(suite, w, c, r, i+1,j, X[i], commit, encShares[i][j])
				}
			}
			logrus.Info("end decryption ")
			return nil
		},
	}

	testOptCmd = &cobra.Command{
		Use:   "opt [node num] [t]",
		Short: "opt [node num] [t]",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			nodeNum, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			t, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			suite := edwards25519.NewBlakeSHA256Ed25519()
			secret := suite.Scalar().SetInt64(123)

			u := t
			n := nodeNum

			x := make([]kyber.Scalar, n) // trustee private keys
			X := make([]kyber.Point, n)  // trustee public keys
			poly := GetSamplePoly(suite, secret)

			for i := 0; i < n; i++ {
				x[i] = suite.Scalar().Pick(suite.RandomStream())
				X[i] = suite.Point().Mul(x[i], nil)
			}
			serverPoints := make([][]share.BiPoint, n)
			encShares := make([][]kyber.Point,n)

			logrus.SetFormatter(&logrus.JSONFormatter{
				TimestampFormat: time.StampMicro,
			})
			logrus.Info("start distribution")
			for i := 0; i < n; i++ {
				serverPoints[i] = make([]share.BiPoint, u)
				encShares[i] = make([]kyber.Point, u)
				for j := 0; j < u; j++ {
					serverPoints[i][j] = poly.Eval(int64(i+1),int64(j))
					encShares[i][j] = suite.Point().Mul(serverPoints[i][j].V,X[i])
				}
			}
			H := suite.Point().Pick(suite.XOF([]byte("H")))
			commit := poly.OptCommit(H,n)
			logrus.Info("end distribution and start decryption")
			w := suite.Scalar().SetInt64(int64(300))
			c := suite.Scalar().SetInt64(int64(2))
			//distribute end
			for i := 0; i < n; i++ {
				r := share.GenerateRScalar(suite, w, c,serverPoints[i][1])
				share.VerifyOptRScalar(suite, w, c, r, i+1,1, X[i], commit, encShares[i][1])
			}
			logrus.Info("end decryption ")
			return nil
		},
	}
)

func GetSamplePoly(suite share.Suite, secret kyber.Scalar) share.BiPoly {
	// make B(x,y) = secret + x + 2x^2 + 3y + 4y^2
	xCoeffs := make([]kyber.Scalar, 2)
	yCoeffs := make([]kyber.Scalar, 2)
	xCoeffs[0] = suite.Scalar().SetInt64(int64(1))
	xCoeffs[1] = suite.Scalar().SetInt64(int64(2))
	yCoeffs[0] = suite.Scalar().SetInt64(int64(3))
	yCoeffs[1] = suite.Scalar().SetInt64(int64(4))

	return share.BiPoly{
		G:       suite,
		Secret:  secret,
		XCoeffs: xCoeffs,
		YCoeffs: yCoeffs,
	}
}
func init() {

	testCmd.AddCommand(testPvssCmd)
	testCmd.AddCommand(testBivssCmd)
	testCmd.AddCommand(testOptCmd)

}
