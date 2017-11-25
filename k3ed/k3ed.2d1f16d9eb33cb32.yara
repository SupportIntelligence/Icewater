
rule k3ed_2d1f16d9eb33cb32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.2d1f16d9eb33cb32"
     cluster="k3ed.2d1f16d9eb33cb32"
     cluster_size="412"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo adplugin"
     md5_hashes="['0036b29cc758010cfd0a4b6a5aae5c38','008c1f366cb8f2b1686926babc0d7205','0d13fbcc22d6e710ebf8208770cb82dc']"

   strings:
      $hex_string = { 7a018a024284c075f92bd752e890ffffff8bd085d27413eb0b660fbec1466689028d52028a0e84c975ef5f5e5dc20400558bec51515356578b7d088bf7894df8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
