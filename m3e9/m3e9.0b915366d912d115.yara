
rule m3e9_0b915366d912d115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b915366d912d115"
     cluster="m3e9.0b915366d912d115"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy scudy"
     md5_hashes="['96803b8d4729648d5efadac75b15f455','a1fc1f711bdffcc0efa80f1b154a25fa','f656b0284b7e2184eed46f5059c2f3a0']"

   strings:
      $hex_string = { fb7dbc92c0aef8f4df095c4d95dc36c6aa5706747f82b56d8ec2d8ac689f841a71e6c93e53cad7b96be78d5f913ba672703d837ba9bc10faed7ecf3fe3cb0562 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
