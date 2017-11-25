
rule m2321_0a6b316910dc4a4e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0a6b316910dc4a4e"
     cluster="m2321.0a6b316910dc4a4e"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['3495ea084e98a4365dbbc485d73653f5','69909b6790f70069c329b056bfed4ec3','f1dd225381599396df4f76b9db01522e']"

   strings:
      $hex_string = { 8e1c4287842971304175ceb974f4df5cd798e4bc3be71da3226db726c863c6c00c60271278fe3e6c1f2ba88cba61d923e61096ae372c1e20060a3a4cbd2d435a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
