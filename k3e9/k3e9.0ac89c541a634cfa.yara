
rule k3e9_0ac89c541a634cfa
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0ac89c541a634cfa"
     cluster="k3e9.0ac89c541a634cfa"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['04da240243bd2a0609fdee4f7a479614','1513ade3dbe0fa2b0fe7f9bb576b99d4','cb7ac85367445e3d441be628607b3f56']"

   strings:
      $hex_string = { b62b3930a2a6ffa85ca976ab14da7948e6567303b828a19c3146d0906c65aff1e102252112ef1028a01ff0d704c554bfaa8c273ae217b2fa3bf96ef747f2bd2e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
