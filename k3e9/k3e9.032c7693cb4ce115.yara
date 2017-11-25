
rule k3e9_032c7693cb4ce115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.032c7693cb4ce115"
     cluster="k3e9.032c7693cb4ce115"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart peed backdoor"
     md5_hashes="['12dcbf9305153fcc200ea8908d56e1d4','1abf3753bf11e5a97b8d8c97c5e3ba81','d359e8a695b2e87118a017feb6230463']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
