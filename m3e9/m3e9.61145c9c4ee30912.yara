
rule m3e9_61145c9c4ee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61145c9c4ee30912"
     cluster="m3e9.61145c9c4ee30912"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbinject diple"
     md5_hashes="['01175bc870f8bee592e72685ae12b78f','1c9821b823f1e6048668afb78ad3200b','a6db62bfa7f2e537cd77226bd5196c16']"

   strings:
      $hex_string = { 6a04e803d0feff83c4148d8570ffffff506a00e8b0cffeffc38d4db8e8d1cffeffc38b45dc8b4de064890d000000005f5e5bc9c21400558bec83ec1868562f40 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
