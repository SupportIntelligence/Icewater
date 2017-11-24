
rule k2321_091e8d9dc6230b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.091e8d9dc6230b32"
     cluster="k2321.091e8d9dc6230b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre jqvu bublik"
     md5_hashes="['3e49b3806c6d5261162061e5c8f73fb3','a48a3aea3386221cd5c0d15bfcf83e5d','c1734cf593eef364adfcb56f10048541']"

   strings:
      $hex_string = { 967a4a14f53ee215bb64e056a94e8a8665ef871a4db23a69cd60a657f495499ae49094f821339155fab3635531747dc367cb43dd848298c44404f1e724c2ccd1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
