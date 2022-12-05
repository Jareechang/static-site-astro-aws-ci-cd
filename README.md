# Astro: CI/CD with AWS and Github Actions

Set up an automated CI/CD pipeline with Astro.

Link to tutorial - [Astro: CI/CD with AWS and Github Actions](https://www.jerrychang.ca/writing/static-site-astro-with-aws-ci-cd).

# Technologies

- [Terraform](https://github.com/hashicorp/terraform)
- [Astro](https://astro.build/)
- AWS
  - Cloudfront
  - S3
- Github Actions 

# Running the site

1. Add a `.env` file
2. Add the unsplash API key (ie `UNSPLASH_API_KEY=xxxx`)
3. Run `pnpm dev` or `pnpm build` (`pnpm` can be swapped with `yarn` or `npm`)
