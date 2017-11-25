
rule k3f7_15d37954dae30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.15d37954dae30b32"
     cluster="k3f7.15d37954dae30b32"
     cluster_size="44"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['05ed9d9b4638fdb0dd6b0a4ec7d09176','0d874ee4a92797bdb884a4145f7f9bbc','5afc21d793a340eb3c737110b60e9f63']"

   strings:
      $hex_string = { 78742f6a617661736372697074273e696628646f63756d656e742e676574456c656d656e74427949642827486964654d65426574746572272920213d206e756c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
