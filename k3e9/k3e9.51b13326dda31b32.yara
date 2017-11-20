
rule k3e9_51b13326dda31b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13326dda31b32"
     cluster="k3e9.51b13326dda31b32"
     cluster_size="1679"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['021bdec474fdf559c28a298e5f9908d0','02709c8e72efb115bb4cbf38a1e145fa','0d7a428e6f2e60da6c2fc6a9b15a1a03']"

   strings:
      $hex_string = { 0003000150000000002800530056000a00e803ffff8000260044006f006e00270074002000720065006d0069006e00640020006d006500200061006700610069 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
