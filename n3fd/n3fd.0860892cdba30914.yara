
rule n3fd_0860892cdba30914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.0860892cdba30914"
     cluster="n3fd.0860892cdba30914"
     cluster_size="87"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox hacekomoe yontoo"
     md5_hashes="['01d9ce547b88479b6e879aefae9b78cc','0286601b3aec9053f51e4ca691161937','2fd6d789fec974fa917d8124c58bb82a']"

   strings:
      $hex_string = { 53746172740061726773004f6e53746f7000633865316436383435326431333236633330656137363962303664633066383337004f6e437573746f6d436f6d6d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
