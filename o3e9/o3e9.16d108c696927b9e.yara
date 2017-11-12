
rule o3e9_16d108c696927b9e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.16d108c696927b9e"
     cluster="o3e9.16d108c696927b9e"
     cluster_size="962"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster malicious attribute"
     md5_hashes="['0005fe8f98fbdfb31344c4fa4e73f7c8','0030bd085d1a26c7c89643f3b468da61','03421fb20a91bf7664133c3507f2af62']"

   strings:
      $hex_string = { 3a57b44b27df6f1225d5d977bdc2b081e98b42822cb6659e00dd4e51c54afdbe0f6d9cad86a593aba3635808e3fc8de89a22a78753a97ec09d498444d33c2002 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
