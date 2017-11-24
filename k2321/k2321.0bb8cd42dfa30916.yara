
rule k2321_0bb8cd42dfa30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0bb8cd42dfa30916"
     cluster="k2321.0bb8cd42dfa30916"
     cluster_size="4"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jtlp kryptik hupigon"
     md5_hashes="['107ede5aa266e67a1cc30974318a40f9','399afb24033e7fb1ca26513ca6eb7ace','de537440fd8cec123fbc7b5ac28e11e1']"

   strings:
      $hex_string = { 6b8fbeec58afb3bbe89e9af94716229da096d1e2baf0b5a9a255894127dbae5d68b04b3f1053e779d66cf8710acddedd62ad1d369f884bbccfb63ec83826bd5b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
