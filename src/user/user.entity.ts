import { BeforeInsert, Column, Entity, PrimaryGeneratedColumn } from 'typeorm'
import * as bcrypt from 'bcryptjs'
import * as jwt from 'jsonwebtoken'

@Entity('user')
export class UserEntity {

  @PrimaryGeneratedColumn('uuid')
  id: number

  @Column({length: 100})
  fullName: string

  @Column({
    unique: true,
    length: 50,
  })
  username: string

  @Column({length: 50})
  phoneNumber: string

  @Column({length: 100})
  email: string

  @Column({length: 255})
  password: string

  @Column({length: 100})
  profession: string

  @Column({width: 100, default: 0})
  account: number

  @Column({length: 255, default: ""})
  picture: string

  @Column({default: false})
  verified: boolean

  @Column({default: false})
  admin: boolean

  @Column({default: () => "NOW()"})
  createdAt: Date

  @BeforeInsert()
  async hashPassword(){
    this.password = await bcrypt.hash(this.password, 10)
  }

  toResponseObject(showToken=true){
    const {id , createdAt, username, token } = this
    const responseObject: any = {id , createdAt, username }
    if (showToken){
      responseObject.token = token
    }
    return responseObject
  }

  async comparePassword(attempt: string){
    return await bcrypt.compare(attempt, this.password)
  }

  private get token(){
    const {id, username} = this
    return jwt.sign({
      id,
      username }, process.env.SECRET, {expiresIn: '7d'})
  }

}
