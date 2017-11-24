
rule k2321_091c95e1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.091c95e1c2000b32"
     cluster="k2321.091c95e1c2000b32"
     cluster_size="4"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre jqvu bublik"
     md5_hashes="['1c2aab76bbb42a07c704c95bd4b7e6be','5633bb59a2c4798a6a621fea35fa1dc5','ee9749f14dbabab79b9e2ae72109fe7b']"

   strings:
      $hex_string = { 967a4a14f53ee215bb64e056a94e8a8665ef871a4db23a69cd60a657f495499ae49094f821339155fab3635531747dc367cb43dd848298c44404f1e724c2ccd1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
