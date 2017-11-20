
rule m3e9_3c19521cc5bb0b22
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3c19521cc5bb0b22"
     cluster="m3e9.3c19521cc5bb0b22"
     cluster_size="2797"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="parite pate shodi"
     md5_hashes="['0005d5fe82a538ce80ad6d307ede2606','0031d0754f2d6aa81bc3e0c8975f9b93','02e8dccc14a8b053eab4d8646a311fd1']"

   strings:
      $hex_string = { 6d4be909449ec2fc41d00ddc6b22d502064a8fb6b7568dae33fdd215f6310f8370f1f7e311b2b925625e84f4269f694c64878c16ced1c30135a8c163afb15d9d }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
