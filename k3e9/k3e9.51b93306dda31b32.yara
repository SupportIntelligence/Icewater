
rule k3e9_51b93306dda31b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93306dda31b32"
     cluster="k3e9.51b93306dda31b32"
     cluster_size="322"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob pornoblocker"
     md5_hashes="['032cc9d6ab95f0d08ddba03660fd0c58','04425bdf64c0d7a12eac2cfa3465605f','35bf441d7549dd52d2af4190b6575333']"

   strings:
      $hex_string = { 0003000150000000002800530056000a00e803ffff8000260044006f006e00270074002000720065006d0069006e00640020006d006500200061006700610069 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
