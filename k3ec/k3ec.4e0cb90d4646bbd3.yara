
rule k3ec_4e0cb90d4646bbd3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.4e0cb90d4646bbd3"
     cluster="k3ec.4e0cb90d4646bbd3"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virtob virut advml"
     md5_hashes="['01e6ea26a6dd8ec46d2c6756dbaa14a4','0fbc1dd2e0099a5d34bf21c8598fa942','f95a30e3e68dfea48eb565405cf5af0d']"

   strings:
      $hex_string = { 45bc1b55c02b7dc41b5dc803f88bcb13ca33db536a025157e8ad2600008946288b463489562c3b45d875090fb645cd394638742e8b46443bc3740a50ff150c11 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
