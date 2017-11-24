
rule n2321_611310d2dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.611310d2dee30932"
     cluster="n2321.611310d2dee30932"
     cluster_size="151"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bublik generickd upatre"
     md5_hashes="['00d6b9adf7ee4468cfd7d840b1115416','02e21807d04a20f4da23299b3d1d6be3','1a1ef109be8a72f2a1ff325a36dae954']"

   strings:
      $hex_string = { bb640a0cf46fd81e87df771fc25ffd92a2cbfa34fb1423453d8fa8bd95a6ad996729c0177cdaae7126f153024fc1501344f5b26e65bec3b754cfb33b524338cc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
