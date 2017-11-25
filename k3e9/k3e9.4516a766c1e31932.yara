
rule k3e9_4516a766c1e31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4516a766c1e31932"
     cluster="k3e9.4516a766c1e31932"
     cluster_size="142"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="servstart nitol daaa"
     md5_hashes="['007f10c8630141eef9d21d61d8d32213','00b79af1e3c643575103de68271b1dc3','13b8257e266fde335c493f12b3b223fd']"

   strings:
      $hex_string = { c083fe017e208bd657d1ea8bcaf7d98d344e8b4c240c33ff668b3983c10203c74a75f35feb048b4c240885f65e740633d28a1103c28bc825ffff0000c1e91003 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
