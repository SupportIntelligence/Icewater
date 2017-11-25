
rule n3e9_161db52bc6220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.161db52bc6220b14"
     cluster="n3e9.161db52bc6220b14"
     cluster_size="194"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="silentinstaller unwanted auslogics"
     md5_hashes="['007aadd4038df499992cb487cb3134e8','01e2961b4cbca63219b35ebd4aa16e51','14ef8be0e70e0e10149663cbf7aca349']"

   strings:
      $hex_string = { 5c3145b52aa5c510d1b11b1655b452fc8edef19df370f9ae5ecea31fd02b9c3bff4607c476c5e880dda2efc80fc29a58ea7a61412c75a9f047e1bad433a6302e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
