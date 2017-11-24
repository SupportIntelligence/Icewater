
rule o2321_6912258cea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.6912258cea210912"
     cluster="o2321.6912258cea210912"
     cluster_size="52"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="filetour symmi feos"
     md5_hashes="['13bf905a4f52661ae9211447c17af190','148aa4a5a1d1f385da2d7298cb1200fa','5bbb3034a68d8c0c9f082b9d01bf03b7']"

   strings:
      $hex_string = { 7093d75db6551c2f614d5a7fcff39b0e4341f074781d0194852be128440b127d180656ff97abe3fe47b7ba1f96669ad9c9133f91b8ccb2bd0dda04774999faa8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
