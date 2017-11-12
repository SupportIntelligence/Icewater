
rule m3e9_3a717b09c0000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a717b09c0000b14"
     cluster="m3e9.3a717b09c0000b14"
     cluster_size="24"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking fujacks malicious"
     md5_hashes="['143dae75429b089c57ab9afd33e0306c','90a4737d1d72d3bb80113d924223c8d4','c5859dc33bb5c7b33707069748eacedc']"

   strings:
      $hex_string = { 49b64807025466c1d98c5b1fc00021bba32f0478618720024900f14bc20ba902e9f6018f714618583713f223b5d4b3b785f72562077a73df03530d16b7538d50 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
