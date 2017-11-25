
rule k3e9_0349969c1e996d96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0349969c1e996d96"
     cluster="k3e9.0349969c1e996d96"
     cluster_size="4054"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd softcnapp taranis"
     md5_hashes="['001b5a0fb7844ef168d263449ff65c2f','001c2428781ecb83347965993aa4b86e','00e2fa2cbd7ed1da202355efadf4838d']"

   strings:
      $hex_string = { 4641fbaf01e59f6fd5ba0f189cf4634b775b6a1a887a9b12c9aedb543ab7f1e73805113f5cd6b229c820a94571fdfeb3030ef395c12d25134874bb33dceee493 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
