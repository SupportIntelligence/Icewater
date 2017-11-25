
rule k3f7_490e36c9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.490e36c9c4000932"
     cluster="k3f7.490e36c9c4000932"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['096df83b3f4c43a44103f5015760c78b','0eb0773ae90ff67640eb8354e8044adf','e2c7b280d580d0f437a4cbccb277cfab']"

   strings:
      $hex_string = { 6669656c642e64656661756c7456616c75653b207d207d0d0a3c2f7363726970743e0d0a3c21444f43545950452068746d6c205055424c494320222d2f2f5733 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
