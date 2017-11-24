
rule m2321_09169019fa630932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.09169019fa630932"
     cluster="m2321.09169019fa630932"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar shyape virtob"
     md5_hashes="['166425f27a454531d5d0d2b51f5ae2a0','48b4b1076539fe477749223ffb17418a','f39585ffeb8eb821ceefcfca458ee345']"

   strings:
      $hex_string = { 97b90feb87188af07125884b2dad320ca86fe3742b949be58d6b90d80bd393ef516a8f84bd14dc821cbf64a0b10aa3949fe1a6b5651b6efd452461b091b4c1ee }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
