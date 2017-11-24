
rule k3e9_41342be3a0c44b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.41342be3a0c44b36"
     cluster="k3e9.41342be3a0c44b36"
     cluster_size="35"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['020467b8aea71f1291b099fc300bf918','26d4b39111a1036570f84e1f4dded4a0','e03f35d88985b7f37c333416a286d613']"

   strings:
      $hex_string = { cc6a0c68386b0001e8a3fbffff33c08b4d0885c9744483f9ff743f2145fcba4d5a0000663911752b8b513c85d27c2481fa00000010731c8d040a8945e4813850 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
