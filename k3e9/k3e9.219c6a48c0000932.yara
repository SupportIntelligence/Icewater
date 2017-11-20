
rule k3e9_219c6a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.219c6a48c0000932"
     cluster="k3e9.219c6a48c0000932"
     cluster_size="26"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol fdld dropped"
     md5_hashes="['042c61569399786336bb321bd8ae1cf7','0b225c85f269d5b92e668ab20a655189','7049dd035460cce28764c722bf7465ad']"

   strings:
      $hex_string = { d32f4c506cea84c5a651b16f726d8b0e58b1e69ff0c7ba9d780cce37c9c2e74d91b64f48c0ad9554fdd6f3acdf7a810d68cf860267f587b47ffa650929061b34 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
