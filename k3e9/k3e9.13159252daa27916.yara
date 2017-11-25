
rule k3e9_13159252daa27916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13159252daa27916"
     cluster="k3e9.13159252daa27916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['139086ff8e9283a8ebaf90995ac61f53','61ea62ea2723f263244ae6a8ea4ac3c0','ec2a57dc82bdc2f3eab17a4c0a198778']"

   strings:
      $hex_string = { b8e2d8ed139b944adcd377251eaf547a201207938a637cf86e252b437d090c5e37b02a0e6f80863a8feeb7bc46fd857fc656b2d6b5d5cd7e3d5cad1c2eba9d70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
