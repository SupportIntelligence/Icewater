
rule k3e9_063cee1dd29b9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.063cee1dd29b9912"
     cluster="k3e9.063cee1dd29b9912"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart berbew peed"
     md5_hashes="['5c010268a4f4ba753c72914e7ee2bead','ce7e97843a0f02aa5dff2c028e21e4fb','e27bf23d9f6708e4745bd60316d93de3']"

   strings:
      $hex_string = { 7b027374726e636d70000000970276737072696e746600006f6c6533322e444c4c00000000f0420000f0420000f0420000f042004f4c4541555433322e444c4c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
