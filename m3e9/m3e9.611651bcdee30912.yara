
rule m3e9_611651bcdee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611651bcdee30912"
     cluster="m3e9.611651bcdee30912"
     cluster_size="303"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt vobfus autorun"
     md5_hashes="['00608c6266738b76c481426fa75b0552','04b02b5018958e6f058ff85fcf4fba59','12687d582cf85ae88a43ad42a08bab92']"

   strings:
      $hex_string = { 6de7feff8d45b0508d45c0506a02e87ee8feff83c40cc3c38d75d08b7d08a5a5a5a58b45088b4de064890d000000005f5e5bc9c20c00558bec83ec1868563440 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
