
rule k3ec_172a56c49ebd6926
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.172a56c49ebd6926"
     cluster="k3ec.172a56c49ebd6926"
     cluster_size="5"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="antavmu fileinfector acaohle"
     md5_hashes="['84f2f4198f8fe7f8668566ba277c7839','adfd26de74dcfc7ee6ca9ea285a9211e','c64fff5747c92715e6840824560c98ff']"

   strings:
      $hex_string = { ff520fbe4f1651e8810f000083c40c3bf07410f6471302750a66834f121083c8ffeb0433c08ac35f5e5b595dc3558bec53568b750c8b5d0885db7505bb72e940 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
