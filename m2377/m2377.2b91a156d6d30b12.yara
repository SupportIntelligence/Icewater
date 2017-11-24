
rule m2377_2b91a156d6d30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b91a156d6d30b12"
     cluster="m2377.2b91a156d6d30b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['018008f4f3e9b037afaef9b4cfcd59ee','7a80471b4361643e74e48c5de0b1de61','fbb363a495bf0576f89397bfec307874']"

   strings:
      $hex_string = { 4141626f772f764e304b33597a616336302f7337322d632f4272756e612b46657272617a2b30312e6a7067272077696474683d273732272f3e0a3c2f613e0a3c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
