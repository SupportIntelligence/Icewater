
rule n3e9_219d2249c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.219d2249c0000b32"
     cluster="n3e9.219d2249c0000b32"
     cluster_size="376"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kryptik razy zaccess"
     md5_hashes="['0002e607a6e6217843f3bb9d8ffec13f','00321193dfde612775118a241857c9d7','1c2b5677838d63bfffa4b6ae2a19f792']"

   strings:
      $hex_string = { 69cffd4c109c4bfc3f78e52b89c38755d0b9a3c779cb0000b423e6092f68f983f4268845ac994bf8ef5ef173dd9813282e620103e9cb8502b766f98bb1fb8642 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
