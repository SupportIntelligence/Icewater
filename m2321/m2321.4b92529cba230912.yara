
rule m2321_4b92529cba230912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4b92529cba230912"
     cluster="m2321.4b92529cba230912"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sality vobfus jorik"
     md5_hashes="['791abbe9fea370b4d0bcf084cae8f1e1','7c1afa9e1a9dd4255992d4607abcd38e','fe936340c1ef073c81f71fc1c0b1b180']"

   strings:
      $hex_string = { fdd3dd62066d2b05c374eaa47cefaf853370b5a6410a8d96a33652c60190e1aaedd1db1f61d78223f2ee60f4f54bb9f6c868bf854857862479b4e20075329a44 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
