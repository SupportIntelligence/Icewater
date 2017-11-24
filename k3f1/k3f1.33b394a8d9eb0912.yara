
rule k3f1_33b394a8d9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f1.33b394a8d9eb0912"
     cluster="k3f1.33b394a8d9eb0912"
     cluster_size="4"
     filetype = "Zip archive data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos smssend trojansms"
     md5_hashes="['63c25f9c710e04c11bf981d3492955fd','6d46410561003a88f1609a2d8a5c10b9','a1c27d7489336227c0916c403e9f01f4']"

   strings:
      $hex_string = { 79e6e2bbb0f722e3a48f998dbe6a091508fa09196642789776a318e921b1d65eadb98312421bf2a5779c34326240b81eb6a00226c129ed4661bc03715f90d5a7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
