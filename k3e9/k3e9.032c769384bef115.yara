
rule k3e9_032c769384bef115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.032c769384bef115"
     cluster="k3e9.032c769384bef115"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart peed backdoor"
     md5_hashes="['2091893b213084d0cdc2878fa000162d','81b484c0452f76bb8648f8fb80784114','c7143c0ddb70555550c96bfeb51851b1']"

   strings:
      $hex_string = { 73734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e45786563 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
