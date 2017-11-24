
rule m3e9_248c33434fa28932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.248c33434fa28932"
     cluster="m3e9.248c33434fa28932"
     cluster_size="48"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik fbor"
     md5_hashes="['0ba525d85370410b6bfb913c743c06d7','1056a48dd9af0e6e0b4cde37fcc66b33','adee7aecdcc2811848f468a21858ab44']"

   strings:
      $hex_string = { 6e5cfff402ebb6fbe6f407ebaf3708b4fe0dec00040000170808008a4400fd9cb0fe08b4fe0d4c0204001ab0fe001304aefe10c80709006baefef400c61ce708 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
