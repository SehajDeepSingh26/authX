"use client";
import React, { useEffect, useState } from "react";
import Link from "next/link";
import { signIn, useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { FcGoogle } from "react-icons/fc";
import Image from "next/image";
import toast from "react-hot-toast";


const NextLoginPage = () => {
    const router = useRouter();
    const [error, setError] = useState("");
    // const session = useSession();
    const { data: session, status: sessionStatus } = useSession();

    useEffect(() => {
        if (sessionStatus === "authenticated") {
            router.replace("/dashboard");
        }
    }, [sessionStatus, router]);

    const isValidEmail = (email: string) => {
        const emailRegex = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
        return emailRegex.test(email);
    };

    const handleSubmit = async (e: any) => {
        e.preventDefault();
        const email = e.target[0].value;
        const password = e.target[1].value;

        if (!isValidEmail(email)) {
            setError("Email is invalid");
            toast.error("Email is invalid");
            return;
        }

        if (!password || password.length < 8) {
            setError("Password is invalid");
            toast.error("Password is invalid");
            return;
        }

        const res = await signIn("credentials", {
            redirect: false,
            email,
            password,
        });

        if (res?.error) {
            setError("Invalid email or password");
            toast.error("Invalid email or password");
            if (res?.url) router.replace("/dashboard");
        } else {
            setError("");
            toast.success("Successful login");
        }
    };

    if (sessionStatus === "loading") {
        return <h1>Loading...</h1>;
    }
    return (
        sessionStatus !== "authenticated" && (
            <div className="flex min-h-full flex-1 flex-col justify-center py-12 sm:px-6 lg:px-8">
                <div className="flex justify-center flex-col items-center">
                    <Image src="/logo 1.png" alt="star logo" width={50} height={50} />
                    <h2 className="mt-6 text-center text-2xl leading-9 tracking-tight text-gray-900">
                        Sign in to your account
                    </h2>
                </div>

                <div className="mt-10 sm:mx-auto sm:w-full sm:max-w-[480px]">
                    <div className="bg-white px-6 py-12 shadow sm:rounded-lg sm:px-12">
                        <form className="space-y-6" onSubmit={handleSubmit}>
                            <div>
                                <label
                                    htmlFor="email"
                                    className="block text-sm font-medium leading-6 text-gray-900"
                                >
                                    Email address
                                </label>
                                <div className="mt-2">
                                    <input
                                        id="email"
                                        name="email"
                                        type="email"
                                        autoComplete="email"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                            </div>

                            <div>
                                <label
                                    htmlFor="password"
                                    className="block text-sm font-medium leading-6 text-gray-900"
                                >
                                    Password
                                </label>
                                <div className="mt-2">
                                    <input
                                        id="password"
                                        name="password"
                                        type="password"
                                        autoComplete="current-password"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                            </div>



                            <div className="flex items-center justify-between">
                                <div className="flex items-center">
                                    <input
                                        id="remember-me"
                                        name="remember-me"
                                        type="checkbox"
                                        className="h-4 w-4 rounded border-gray-300 text-black focus:ring-black"
                                    />
                                    <label
                                        htmlFor="remember-me"
                                        className="ml-3 block text-sm leading-6 text-gray-900"
                                    >
                                        Remember me
                                    </label>
                                </div>

                                <div className="text-sm leading-6">
                                    <Link
                                        href="#"
                                        className="text-black hover:text-gray-900"
                                    >
                                        Forgot password?
                                    </Link>
                                </div>
                            </div>

                            <div>
                                <button
                                    type="submit"
                                    className="flex w-full border border-black justify-center rounded-md bg-black px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-white transition-colors hover:text-black focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
                                >
                                    Sign in
                                </button>
                            </div>
                        </form>

                        <div>
                            <div className="relative mt-10">
                                <div
                                    className="absolute inset-0 flex items-center"
                                    aria-hidden="true"
                                >
                                    <div className="w-full border-t border-gray-200" />
                                </div>
                                <div className="relative flex justify-center text-sm font-medium leading-6">
                                    <span className="bg-white px-6 text-gray-900">
                                        Or continue with
                                    </span>
                                </div>
                            </div>

                            <div className="mt-6 grid grid-cols-2 gap-4">
                                <button
                                    onClick={() => {
                                        signIn("google");
                                    }}
                                    className="flex w-full items-center border border-gray-300 justify-center gap-3 rounded-md bg-white px-3 py-1.5 text-black focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
                                >
                                    <FcGoogle />
                                    <span className="text-sm font-semibold leading-6">
                                        Google
                                    </span>
                                </button>

                                <button
                                    onClick={() => {
                                        signIn("twitter");
                                    }}
                                    className="flex w-full items-center justify-center gap-3 rounded-md bg-[#24292F] px-3 py-1.5 text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#24292F]"
                                >
                                    <svg
                                        className="h-5 w-5"
                                        aria-hidden="true"
                                        fill="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path d="M20.98 3.5h-3.92l-4.27 5.78-4.4-5.78H2.26l6.93 8.91L2.1 20.5h3.92l4.67-6.34 4.83 6.34h6.22l-7.16-9.28L20.98 3.5z" />
                                    </svg>

                                </button>

                            </div>
                            <p className="text-red-600 text-center text-[16px] my-4">
                                {error && error}
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        )
    );
};

export default NextLoginPage;
