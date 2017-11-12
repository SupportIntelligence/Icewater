
rule n3e9_50992949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.50992949c0000b32"
     cluster="n3e9.50992949c0000b32"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer malicious"
     md5_hashes="['4a739ca7e151d4891490a7d3511b610a','b978f2b6a3fcae62137c398ff744df78','eb4bb1ff2289434bc7b6bf919bcefb06']"

   strings:
      $hex_string = { afb61343b1e55d5177dd97f6525dcd73d54bdcd2cf87c9e3028fc968127765a8a6c82158cec73e5bc7d9d4d7e6417828c2dbcad7e0cbc3cfc8c73a3a28dadb80 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
