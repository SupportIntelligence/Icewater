
rule k3ec_4b5695a9c6420b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.4b5695a9c6420b12"
     cluster="k3ec.4b5695a9c6420b12"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virtob virut advml"
     md5_hashes="['00754dc57f014517a94af0c0874352cc','016d977ad50c68f3653f68f6336c4ee0','c87f05f002e25763b2f412b063b8c66b']"

   strings:
      $hex_string = { 10000064000000f031f431f83104320832243728376c37703722388b3896389c38cd38eb3863398d39a139e639f539173a283a303a4c3a743a823a893a9b3aac }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
