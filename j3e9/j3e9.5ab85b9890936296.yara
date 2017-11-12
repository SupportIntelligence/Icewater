import "hash"

rule j3e9_5ab85b9890936296
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.5ab85b9890936296"
     cluster="j3e9.5ab85b9890936296"
     cluster_size="4400"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre zbot generickd"
     md5_hashes="['00064c319623f7df17593e65c80f3f55','001432906191607d629ba59fd6affbfc','02d96fa199c16ee9e7d2317a5fc62c0c']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,4096) == "cbdc3209906de287cf264adb20d8d399"
}

