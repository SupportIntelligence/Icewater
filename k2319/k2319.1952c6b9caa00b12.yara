
rule k2319_1952c6b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1952c6b9caa00b12"
     cluster="k2319.1952c6b9caa00b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d8f94d238da57b685071fd7aea732f7097f528be','2ba776b0a7c8e3986f596b91a123a40a6b16cbd2','6360da6ec4858b56ad0a714e8a3b461b7f29c460']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1952c6b9caa00b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20545b6c5d3b7d76617220463d28362e303345323c3d2830783143362c3532293f2839302c313333293a28307832342c38312e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
