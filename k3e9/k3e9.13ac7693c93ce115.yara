
rule k3e9_13ac7693c93ce115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13ac7693c93ce115"
     cluster="k3e9.13ac7693c93ce115"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart peed backdoor"
     md5_hashes="['1bfeba5977bae312952fb0b568f1ed0f','c3c174dc01f365f8dcdebaee972d55c7','fb0b65c41aa74322d01da058e774c8c5']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
