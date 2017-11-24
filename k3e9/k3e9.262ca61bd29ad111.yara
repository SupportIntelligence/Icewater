
rule k3e9_262ca61bd29ad111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.262ca61bd29ad111"
     cluster="k3e9.262ca61bd29ad111"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart genpack backdoor"
     md5_hashes="['c230fdc875314f4ce37a64e6ae3d783d','c250a3764aa461cdbc82498b18a25588','fab4a6a4bf8dfbdb9d4fa1cc956f9e39']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
