
rule m2321_1391856adabb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1391856adabb0912"
     cluster="m2321.1391856adabb0912"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['1f5e64724e301eed1254f4a977373bd8','368f6eb983b1399b15bbef3a41aa1cf7','d9296b4bdabb63cfb8279144e8f2da49']"

   strings:
      $hex_string = { 1f3b2c5a6ad7f26cd95ffbb2f778679488ab5b0d982b2ad66e3842551946d3b4133e18bcfe253ccf56c40fb058a3ae4a570050631ca03a548be1a8dc70aa6404 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
