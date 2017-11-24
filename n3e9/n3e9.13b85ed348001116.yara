
rule n3e9_13b85ed348001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13b85ed348001116"
     cluster="n3e9.13b85ed348001116"
     cluster_size="43"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun vilsel"
     md5_hashes="['139293b5cad5ef8d61c2bc338ecdb055','16859c8e2dce6abe7e7b8469ea695651','af7ff24524baadeb20f5e4d8da2abdff']"

   strings:
      $hex_string = { f004c8f768c1d85596a3dc5bb0599163247e10aa8547a937fd780cbcd6effa0ef55a67379b2e734c922b9aa1a077863adabf510a8d50d138c93e9416122a9f5f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
