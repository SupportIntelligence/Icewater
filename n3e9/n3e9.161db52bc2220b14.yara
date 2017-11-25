
rule n3e9_161db52bc2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.161db52bc2220b14"
     cluster="n3e9.161db52bc2220b14"
     cluster_size="540"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="auslogics silentinstaller unwanted"
     md5_hashes="['00839ac456b24cac4967c1516fb2f707','01be0d879e05249ebdd281ace04d53db','0b2440142a4a74840450efe7635163f0']"

   strings:
      $hex_string = { 5c3145b52aa5c510d1b11b1655b452fc8edef19df370f9ae5ecea31fd02b9c3bff4607c476c5e880dda2efc80fc29a58ea7a61412c75a9f047e1bad433a6302e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
