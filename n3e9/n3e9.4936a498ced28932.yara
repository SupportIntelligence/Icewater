
rule n3e9_4936a498ced28932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4936a498ced28932"
     cluster="n3e9.4936a498ced28932"
     cluster_size="100"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob vetor"
     md5_hashes="['051bdd635d881a55883f0f382a652d2c','080c203e05667a70b7c4474355cdbdb0','baffef411508989cf927a8085aba12d1']"

   strings:
      $hex_string = { ccb8112e0901e8307cfaff83ec10538b5d088d43d4f7d8568d4be41bc023c157508d4d08e813e6f9ff8b550c33ff33f63bd7897dfcb957000780740566393a75 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
