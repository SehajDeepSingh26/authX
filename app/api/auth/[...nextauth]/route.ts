import NextAuth from "next-auth";
import { Account, User as AuthUser } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import TwitterProvider from "next-auth/providers/twitter";
import bcrypt from "bcryptjs";
import User from "@/models/User";
import connect from "@/utils/db";

export const authOptions: any = {
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials: any) {
        await connect();
        try {
          const user = await User.findOne({ email: credentials.email });
          if (user) {
            const isPasswordCorrect = await bcrypt.compare(
              credentials.password,
              user.password
            );
            if (isPasswordCorrect) {
              return user;
            }
          }
        } catch (err: any) {
          throw new Error(err);
        }
      },
    }),

    GoogleProvider({
      clientId: process.env.GOOGLE_ID ?? "",
      clientSecret: process.env.GOOGLE_SECRET ?? "",
    }),

    TwitterProvider({
      clientId: process.env.TWITTER_ID ?? "",
      clientSecret: process.env.TWITTER_SECRET ?? "",
      version: "2.0", // important for OAuth 2.0 with X (Twitter)
    }),
  ],

  callbacks: {
    async signIn({ user, account }: { user: AuthUser; account: Account }) {
      if (account?.provider === "credentials") {
        return true;
      }

      if (account?.provider === "google" || account?.provider === "twitter") {
        await connect();
        try {
          const existingUser = await User.findOne({ email: user.email });
          if (!existingUser) {
            const newUser = new User({
              email: user.email,
            });
            await newUser.save();
          }
          return true;
        } catch (err) {
          console.log("Error saving user", err);
          return false;
        }
      }

      return false;
    },
  },
};

export const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
