
rule m2321_699ee448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.699ee448c0000b32"
     cluster="m2321.699ee448c0000b32"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['79e22743cf7eb34f43a8646f965b54aa','7b8f1109cab938718a24d0aca18e2ede','e872e79a3256befdfe4f65cc9c1b5f08']"

   strings:
      $hex_string = { 87090f976495f348d7f52253417f9692e48dcbbbcf3be7569d33dcee397ef860da21a17c20a5860b83a6f1d024f45d676db7e4b950ba31bcd9ea2fc8a3dfcce6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
