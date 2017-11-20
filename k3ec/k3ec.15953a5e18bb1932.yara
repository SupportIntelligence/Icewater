
rule k3ec_15953a5e18bb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.15953a5e18bb1932"
     cluster="k3ec.15953a5e18bb1932"
     cluster_size="9"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email malicious"
     md5_hashes="['25cdd51a8fca497b65f3154ea6febd8e','ad77b16e0a4ad6733ba6698b391d6f06','da768934f9a56aa3d47b2f961e967236']"

   strings:
      $hex_string = { 537c50c16a31227d3b419ad9d5a7975ce401559d02b803e25af7f6723e14bdfe686c4064d15bee2c9d26f52519a658df009e6e2f700cb02e562474288df0b6e9 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
