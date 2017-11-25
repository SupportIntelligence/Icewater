
rule k3e9_091c97c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.091c97c9cc000b32"
     cluster="k3e9.091c97c9cc000b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre jqvu bublik"
     md5_hashes="['20e61d351088a1c75b50056ca306d11a','5a015dea8cb2ca8caee504107748ffbe','fe3e53bd34f3d7705284f308f8623b01']"

   strings:
      $hex_string = { 967a4a14f53ee215bb64e056a94e8a8665ef871a4db23a69cd60a657f495499ae49094f821339155fab3635531747dc367cb43dd848298c44404f1e724c2ccd1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
